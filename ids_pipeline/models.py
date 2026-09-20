"""Self-supervised models: multi-modal SSL network and a plain autoencoder baseline.

MultiModalSSL learns normal behaviour with two self-supervised objectives:
  1. masked-feature reconstruction (random feature masking + whole-modality dropout),
  2. cross-modal contrastive alignment (InfoNCE between modality embeddings of the same flow).
Anomaly evidence = reconstruction error + cross-modal inconsistency (see scoring.py).
"""
import copy
import itertools

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .features import N_ROLES


def _mlp(i, h, o, depth=1):
    layers, d = [], i
    for _ in range(depth):
        layers += [nn.Linear(d, h), nn.GELU()]
        d = h
    return nn.Sequential(*layers, nn.Linear(d, o))


class MultiModalSSL(nn.Module):
    def __init__(self, slices, mcfg, use_role=True, contrastive_weight=None):
        super().__init__()
        self.slices = slices
        self.mods = list(slices)
        self.D = max(b for _, b in slices.values())
        self.use_role = use_role
        self.mask_ratio = mcfg["mask_ratio"]
        self.mod_drop = mcfg["modality_dropout"]
        self.tau = mcfg["temperature"]
        self.lam = mcfg["contrastive_weight"] if contrastive_weight is None else contrastive_weight
        h, zm, z, rd = mcfg["hidden"], mcfg["modality_dim"], mcfg["latent_dim"], mcfg["role_dim"]
        self.role_dim = rd if use_role else 0
        self.enc = nn.ModuleDict({m: _mlp(b - a, h, zm) for m, (a, b) in slices.items()})
        self.proj = nn.ModuleDict({m: nn.Linear(zm, mcfg["proj_dim"]) for m in self.mods})
        self.role_emb = nn.Embedding(N_ROLES, rd) if use_role else None
        self.fuse = _mlp(zm * len(self.mods) + self.role_dim, h, z)
        self.dec = _mlp(z + self.role_dim, h, self.D, depth=2)

    def _role(self, role, n):
        if self.role_emb is None:
            return torch.zeros(n, 0, device=role.device)
        return self.role_emb(role.long())

    def _forward(self, x, role):
        r = self._role(role, len(x))
        zs = [self.enc[m](x[:, a:b]) for m, (a, b) in self.slices.items()]
        ps = [F.normalize(self.proj[m](z), dim=-1) for m, z in zip(self.mods, zs)]
        h = self.fuse(torch.cat(zs + [r], 1))
        return self.dec(torch.cat([h, r], 1)), ps

    def _contrast(self, ps):
        if len(ps) < 2 or self.lam == 0:
            return ps[0].new_zeros(())
        ps = [p[:256] for p in ps]      # InfoNCE on a 256-flow sub-batch keeps the pairwise logits cheap
        tgt = torch.arange(len(ps[0]), device=ps[0].device)
        loss = 0.0
        pairs = list(itertools.combinations(range(len(ps)), 2))
        for i, j in pairs:
            logits = ps[i] @ ps[j].T / self.tau
            loss = loss + 0.5 * (F.cross_entropy(logits, tgt) + F.cross_entropy(logits.T, tgt))
        return loss / len(pairs)

    def loss(self, x, role):
        xin = x.masked_fill(torch.rand_like(x) < self.mask_ratio, 0.0)
        if self.mod_drop > 0 and len(self.mods) > 1:
            xin = xin.clone()
            for a, b in self.slices.values():
                drop = torch.rand(len(x), 1, device=x.device) < self.mod_drop
                xin[:, a:b] = xin[:, a:b].masked_fill(drop, 0.0)
        recon, ps = self._forward(xin, role)
        l_rec, l_con = F.mse_loss(recon, x), self._contrast(ps)
        return l_rec + self.lam * l_con, {"rec": l_rec.item(), "con": l_con.item()}

    @torch.no_grad()
    def embed(self, x, role):
        """fused latent embedding of a flow (input of the latent-space anomaly detector)"""
        r = self._role(role, len(x))
        zs = [self.enc[m](x[:, a:b]) for m, (a, b) in self.slices.items()]
        return self.fuse(torch.cat(zs + [r], 1))

    @torch.no_grad()
    def components(self, x, role):
        recon, ps = self._forward(x, role)
        err = (recon - x) ** 2
        if len(ps) > 1:
            xm = torch.stack([1 - (ps[i] * ps[j]).sum(-1)
                              for i, j in itertools.combinations(range(len(ps)), 2)]).mean(0)
        else:
            xm = torch.zeros(len(x))
        return {"feat_err": err, "rec": err.mean(1), "xmod": xm}


class MLPAutoencoder(nn.Module):
    """Plain single-view autoencoder on the concatenated features (baseline)."""

    def __init__(self, slices, mcfg, use_role=False, **_):
        super().__init__()
        D = max(b for _, b in slices.values())
        h, z = mcfg["hidden"], mcfg["latent_dim"]
        self.enc, self.dec = _mlp(D, h, z, depth=2), _mlp(z, h, D, depth=2)

    def loss(self, x, role):
        l = F.mse_loss(self.dec(self.enc(x)), x)
        return l, {"rec": l.item(), "con": 0.0}

    @torch.no_grad()
    def embed(self, x, role):
        return self.enc(x)

    @torch.no_grad()
    def components(self, x, role):
        err = (self.dec(self.enc(x)) - x) ** 2
        return {"feat_err": err, "rec": err.mean(1), "xmod": torch.zeros(len(x))}


def train_model(model, Xtr, rtr, Xva, rva, mcfg, log, tag=""):
    torch.set_num_threads(max(1, torch.get_num_threads()))
    opt = torch.optim.AdamW(model.parameters(), lr=mcfg["lr"], weight_decay=mcfg["weight_decay"])
    Xtr, rtr = torch.from_numpy(Xtr), torch.from_numpy(rtr)
    Xva, rva = torch.from_numpy(Xva), torch.from_numpy(rva)
    bs, best, best_state, bad, hist = mcfg["batch_size"], np.inf, None, 0, []
    for ep in range(mcfg["epochs"]):
        model.train()
        perm = torch.randperm(len(Xtr))
        tot = n = 0
        for i in range(0, len(perm) - bs + 1, bs):
            idx = perm[i:i + bs]
            loss, _ = model.loss(Xtr[idx], rtr[idx])
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
            tot, n = tot + loss.item(), n + 1
        model.eval()
        with torch.no_grad():
            g = torch.manual_seed(0)  # deterministic masks -> comparable validation loss
            vl = np.mean([model.loss(Xva[i:i + 8192], rva[i:i + 8192])[0].item()
                          for i in range(0, len(Xva), 8192)])
        hist.append((tot / n, vl))
        log.info("[%s] epoch %2d  train %.4f  val %.4f", tag, ep + 1, tot / n, vl)
        if vl < best - 1e-5:
            best, best_state, bad = vl, copy.deepcopy(model.state_dict()), 0
        else:
            bad += 1
            if bad >= mcfg["patience"]:
                break
    model.load_state_dict(best_state)
    model.eval()
    return hist


def batched_embed(model, X, role, bs=16384):
    model.eval()
    return np.concatenate([model.embed(torch.from_numpy(X[i:i + bs]), torch.from_numpy(role[i:i + bs])).numpy()
                           for i in range(0, len(X), bs)])


def batched_components(model, X, role, bs=16384, keep_feat=False):
    out = {"rec": [], "xmod": [], "feat_err": []}
    model.eval()
    for i in range(0, len(X), bs):
        c = model.components(torch.from_numpy(X[i:i + bs]), torch.from_numpy(role[i:i + bs]))
        out["rec"].append(c["rec"].numpy())
        out["xmod"].append(c["xmod"].numpy())
        if keep_feat:
            out["feat_err"].append(c["feat_err"].numpy())
    res = {k: np.concatenate(v) for k, v in out.items() if v}
    return res

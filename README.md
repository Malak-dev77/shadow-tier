# shadow-tier
Behavioral Intent-Based Deception Architecture for Financial Infrastructure DDoS Defense

# Shadow Tier

**Behavioral Intent-Based Deception Architecture for Financial Infrastructure DDoS Defense**

*Author: Malak Emad — Engineering University, Cairo, Egypt*

---

## What is Shadow Tier?

Every DDoS mitigation platform deployed in financial infrastructure today teaches the attacker how to beat it. When a packet is dropped, the attacker receives a lesson. Shadow Tier breaks that loop.

Shadow Tier introduces a fourth action at the DDoS mitigation layer — one that does not exist in any current commercial product. Instead of dropping sophisticated attack traffic, it redirects it into purpose-built deception infrastructure where the attacker believes they are advancing toward a real target while the defender collects their methodology, signatures, and behavioral patterns in real time.

---

## Architecture — Four Layers

1. **Layer Zero Protocol Deception** — corrupts attacker reconnaissance before classification begins
2. **Behavioral Classifier** — detects persistence, SYN reconnaissance, and directed financial intent simultaneously  
3. **Policy-Based Routing** — silently redirects classified traffic without drop feedback
4. **Non-Linear Honeypot Maze** — engages attacker with convincing false responses while logging all interactions

---

## Validation Results

- Detection Rate: **6/6 rules — 100%**
- False Positive Rate: **0**
- End-to-end deception loop: **Proven**
- Attacker awareness of redirection: **Zero**

---

## Repository Structure

---

## Lab Environment

| VM | IP | Role |
|---|---|---|
| Kali Linux | 192.168.20.2 | Attacker |
| shadowtier-ips | 192.168.20.1 | Detection & routing brain |
| shadowtierhoneynet | 192.168.30.2 | Deception maze (isolated) |

---

## Research Paper

Full IEEE conference paper submitted to top-tier international venue. Available upon request.

---

## Contact

Malak Emad — Cybersecurity Researcher & Network Security Architect  
https://linkedin.com/in/malak-emad-271779266 | malakemad193@gmail.com

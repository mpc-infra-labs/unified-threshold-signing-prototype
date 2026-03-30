# Unified Threshold Signing Prototype

A research prototype for multi-chain MPC signing architecture.

## Overview

This repository validates one practical idea:

- do not hardcode one signing stack per chain
- keep MPC protocol logic reusable
- isolate chain-specific behavior behind adapters

In short, the project explores how one MPC-oriented architecture can support both ECDSA-style and EdDSA-style chains by introducing a custom curve adapter, instead of rebuilding the full signing pipeline for every chain.

## Why This Exists

In production custody or Wallet-as-a-Service systems, the main challenge is not supporting a single chain.  
The challenge is scaling to many chains without fragmenting operations:

- one stack for EVM
- another stack for Solana
- separate keygen, signing, policy, and recovery workflows

This prototype follows a layered hypothesis:

1. keep the protocol layer reusable
2. abstract curve behavior behind a dedicated adapter
3. place chain transaction specifics above that boundary

This separation is what turns a single-chain experiment into a multi-chain foundation.

## Core Idea

The design follows a common custody pattern: reuse a shared MPC core, then bridge chain differences through curve and signer adapters.

This repository uses Taurus `multi-party-sig` as the protocol-oriented base and adds a custom Ed25519 curve implementation so generic threshold-signing math can be reused in an EdDSA flow.

The point is not "Taurus natively supports Solana end to end."  
The point is to prove that a clean curve adapter boundary enables reuse of shared MPC math and workflow logic.

## What Is Demonstrated Today

Current scope is a 2-of-3 Ed25519 threshold-signing experiment:

- simulated DKG
- local share persistence
- threshold signing
- local Ed25519 signature verification

The concrete test path is Solana-compatible Ed25519 accounts, used as a practical target for adapter validation.

## Why Taurus 🧩

Taurus is useful here because it already exposes reusable abstractions for:

- curves
- points and scalars
- polynomial-based share generation
- Lagrange interpolation and related threshold-signing math

That lets this project focus on the adapter boundary instead of reimplementing MPC primitives.

Most importantly, Taurus provides a practical abstraction surface for curve-level customization, which is exactly what this prototype needs for rapid protocol-library modification and validation.

Compared with nearby projects, the alignment with this goal is stronger:

- Synedrion is intentionally focused on a CGGMP'24 threshold ECDSA line, which is strong for deep protocol research but less convenient for fast multi-curve adapter experiments
- Lockness is broader and ecosystem-oriented (multiple framework and protocol repos), powerful for full Rust MPC engineering but heavier for quick single-path curve-bridge validation

For this repository, Taurus is used as a modifiable protocol base where the primary experiment is:
"abstract curve semantics cleanly, then plug chain-specific signers above it."

## Architecture Strategy 🏗️

The target architecture is:

1. protocol layer  
   reusable threshold-signing and share-management logic
2. curve adapter layer  
   curve-specific implementation behind a common interface
3. chain adapter layer  
   chain-specific payload conversion and signed-transaction reconstruction

This repository is mainly focused on step 2.

The current Ed25519 adapter wraps `filippo.io/edwards25519` types into Taurus-style curve interfaces, so generic polynomial and interpolation utilities can be reused directly.

## Repository Scope

This is a research prototype, not a production wallet.

It is designed to answer:

- how protocol logic and chain logic should be separated
- where curve-specific behavior should live
- how much of threshold-signing can be shared across ECDSA and EdDSA paths

It is not intended yet to provide:

- production-grade security guarantees
- audited protocol correctness
- full networking/orchestration across parties
- multi-chain transaction builders
- hardened key management and recovery

## Quick Start 🚀

```bash
go mod tidy
go run main.go
```

Then select:

- `1` for DKG
- `2` for threshold signing

## Current Status

Treat this repository as an architecture and protocol-adaptation experiment.

The current implementation shows that a custom curve layer can bridge generic MPC abstractions with Ed25519-based signing logic, and provides a stepping stone toward a cleaner multi-curve, multi-chain signing infrastructure.

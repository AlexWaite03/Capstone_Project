# dfa.py
# ============================================================
# Minimal DFA implementation over character-class tokens (Tok).
#
# This module provides:
# - DFA data structure (states, transitions, accept states)
# - Subset construction (determinize) from an NFA (nfa.py)
# - DFA simulation on token streams and raw strings (with tokenizer)
# - Optional DFA minimization (simple Hopcroft, kept minimal)
#
# Notes for your capstone:
# - Use determinize() to convert Thompson-style NFAs -> DFAs.
# - You can also hand-build DFAs for counting rules (length/dot count).
# - Keep tokenization consistent with extract_automata_features.py.
# ============================================================

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Set, Tuple, FrozenSet, Iterable, Optional, List

from .nfa import NFA, Tok, eps_closure, move


# ------------------------------------------------------------
# Tokenizer (copy kept minimal here; ideally import from a shared module)
# ------------------------------------------------------------
def char_to_tok(c: str) -> Tok:
    if c.isdigit():
        return Tok.DIGIT
    if c.isalpha():
        return Tok.LETTER
    if c == ".":
        return Tok.DOT
    if c == "/":
        return Tok.SLASH
    if c == "@":
        return Tok.AT
    if c == "-":
        return Tok.HYPHEN
    if c == "%":
        return Tok.PERCENT
    if c == "=":
        return Tok.EQUAL
    if c == "&":
        return Tok.AMP
    if c == "?":
        return Tok.QMARK
    if c == ":":
        return Tok.COLON
    if c == "_":
        return Tok.UNDERSCORE
    return Tok.OTHER


def tokenize(text: str) -> List[Tok]:
    return [char_to_tok(c) for c in text]


# ------------------------------------------------------------
# DFA structure
# ------------------------------------------------------------
DState = FrozenSet[int]  # DFA states are sets of NFA states

@dataclass
class DFA:
    start: DState
    accepts: Set[DState]
    trans: Dict[Tuple[DState, Tok], DState] = field(default_factory=dict)

    # Optional explicit sink state to make simulation total.
    sink: Optional[DState] = None


# ------------------------------------------------------------
# Subset construction (NFA -> DFA)
# ------------------------------------------------------------
def determinize(nfa: NFA, alphabet: Optional[Set[Tok]] = None, add_sink: bool = True) -> DFA:
    """
    Convert an NFA to a DFA via subset construction.

    Params:
      alphabet: set of Tok symbols to consider. If None, uses all Tok.
      add_sink: if True, create an explicit sink state so transitions are total.
    """
    if alphabet is None:
        alphabet = set(Tok)

    start = frozenset(eps_closure(nfa, {nfa.start}))
    unmarked: List[DState] = [start]
    seen: Set[DState] = {start}

    trans: Dict[Tuple[DState, Tok], DState] = {}
    accepts: Set[DState] = set()

    # We'll create sink at end if needed
    sink: Optional[DState] = None
    sink_needed = False

    while unmarked:
        S = unmarked.pop()

        # Accepting if any NFA accept state is in this subset
        if any(s in nfa.accepts for s in S):
            accepts.add(S)

        for tok in alphabet:
            U = eps_closure(nfa, move(nfa, set(S), tok))
            U_set = frozenset(U)

            if not U_set:
                # Missing transition; optionally route to sink
                sink_needed = True
                continue

            trans[(S, tok)] = U_set
            if U_set not in seen:
                seen.add(U_set)
                unmarked.append(U_set)

    if add_sink and sink_needed:
        sink = frozenset()  # represent sink as empty subset
        # Add transitions from all states to sink where missing
        for S in list(seen):
            for tok in alphabet:
                if (S, tok) not in trans:
                    trans[(S, tok)] = sink
        # Add self-loops on sink
        for tok in alphabet:
            trans[(sink, tok)] = sink
        # sink is non-accepting by definition

    return DFA(start=start, accepts=accepts, trans=trans, sink=sink)


# ------------------------------------------------------------
# DFA simulation
# ------------------------------------------------------------
def dfa_accepts_tokens(dfa: DFA, toks: Iterable[Tok]) -> bool:
    state: DState = dfa.start
    for tok in toks:
        nxt = dfa.trans.get((state, tok))
        if nxt is None:
            # If no sink, reject
            return False
        state = nxt
    return state in dfa.accepts


def dfa_accepts_text(dfa: DFA, text: str) -> bool:
    return dfa_accepts_tokens(dfa, tokenize(text))


# ------------------------------------------------------------
# Handy: Build a small counting DFA (for thresholds)
# ------------------------------------------------------------
def build_counting_dfa(
    trigger_tok: Tok,
    threshold: int,
    alphabet: Optional[Set[Tok]] = None,
) -> DFA:
    """
    Build a DFA that accepts iff the number of occurrences of `trigger_tok`
    in the token stream is >= threshold.

    States: {0,1,2,...,threshold} where threshold means "threshold or more".
    """
    if threshold <= 0:
        # Accept everything
        s0 = frozenset({0})
        return DFA(start=s0, accepts={s0}, trans={})

    if alphabet is None:
        alphabet = set(Tok)

    # We'll represent DFA states as frozenset({count})
    def S(i: int) -> DState:
        return frozenset({i})

    start = S(0)
    accepts = {S(threshold)}
    trans: Dict[Tuple[DState, Tok], DState] = {}

    for i in range(0, threshold + 1):
        for tok in alphabet:
            if tok == trigger_tok:
                j = min(threshold, i + 1)
            else:
                j = i
            trans[(S(i), tok)] = S(j)

    return DFA(start=start, accepts=accepts, trans=trans, sink=None)


def build_length_threshold_dfa(threshold: int, alphabet: Optional[Set[Tok]] = None) -> DFA:
    """
    DFA that accepts iff token stream length >= threshold.
    This is the 'very long URL' style DFA.
    """
    if threshold <= 0:
        s0 = frozenset({0})
        return DFA(start=s0, accepts={s0}, trans={})

    if alphabet is None:
        alphabet = set(Tok)

    def S(i: int) -> DState:
        return frozenset({i})

    start = S(0)
    accepts = {S(threshold)}
    trans: Dict[Tuple[DState, Tok], DState] = {}

    for i in range(0, threshold + 1):
        for tok in alphabet:
            j = min(threshold, i + 1)
            trans[(S(i), tok)] = S(j)

    return DFA(start=start, accepts=accepts, trans=trans, sink=None)


# ------------------------------------------------------------
# Optional: DFA minimization (Hopcroft) - kept compact
# ------------------------------------------------------------
def minimize_dfa(dfa: DFA, alphabet: Optional[Set[Tok]] = None) -> DFA:
    """
    Hopcroft minimization for a DFA with total transitions.
    If your DFA has missing transitions, determinize with add_sink=True first.
    """
    if alphabet is None:
        alphabet = set(Tok)

    # Collect all states appearing in transitions
    states: Set[DState] = set([dfa.start]) | set(dfa.accepts)
    for (s, _), t in dfa.trans.items():
        states.add(s)
        states.add(t)

    F = set(dfa.accepts)
    NF = states - F

    # Initialize partition
    P: List[Set[DState]] = []
    if F:
        P.append(F)
    if NF:
        P.append(NF)

    W: List[Set[DState]] = []
    if F:
        W.append(F.copy())
    elif NF:
        W.append(NF.copy())

    def preimage(A: Set[DState], tok: Tok) -> Set[DState]:
        """States that transition on tok into A."""
        out = set()
        for s in states:
            t = dfa.trans.get((s, tok))
            if t in A:
                out.add(s)
        return out

    while W:
        A = W.pop()
        for tok in alphabet:
            X = preimage(A, tok)
            if not X:
                continue
            new_P: List[Set[DState]] = []
            for Y in P:
                inter = Y & X
                diff = Y - X
                if inter and diff:
                    new_P.append(inter)
                    new_P.append(diff)
                    # update W
                    if Y in W:
                        W.remove(Y)
                        W.append(inter)
                        W.append(diff)
                    else:
                        # add smaller part
                        W.append(inter if len(inter) <= len(diff) else diff)
                else:
                    new_P.append(Y)
            P = new_P

    # Map each old state to its block representative
    rep: Dict[DState, DState] = {}
    for block in P:
        r = next(iter(block))
        for s in block:
            rep[s] = r

    new_start = rep[dfa.start]
    new_accepts = {rep[s] for s in dfa.accepts}

    new_trans: Dict[Tuple[DState, Tok], DState] = {}
    for (s, tok), t in dfa.trans.items():
        new_trans[(rep[s], tok)] = rep[t]

    return DFA(start=new_start, accepts=new_accepts, trans=new_trans, sink=rep[dfa.sink] if dfa.sink is not None else None)

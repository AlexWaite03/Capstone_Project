# nfa.py
# ============================================================
# Minimal NFA implementation over character-class tokens (Tok).
#
# This module gives you:
# - NFA data structure (states, transitions, epsilons)
# - epsilon-closure and move functions
# - NFA simulation (membership test) on token streams
# - a tiny builder API (fragments) so you can hand-build NFAs
#
# Notes for the capstone:
# - You can hand-build NFAs for "headline" regex rules (URL-02, URL-11, EMAIL-11, etc.)
# - If you later implement regex -> Thompson construction, you can plug it into this.
# ============================================================

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Set, Tuple, FrozenSet, Iterable, Optional, List
from enum import Enum


# ------------------------------------------------------------
# Token alphabet (keep consistent with extract_automata_features)
# ------------------------------------------------------------
class Tok(Enum):
    DIGIT = "DIGIT"
    LETTER = "LETTER"
    DOT = "."
    SLASH = "/"
    AT = "@"
    HYPHEN = "-"
    PERCENT = "%"
    EQUAL = "="
    AMP = "&"
    QMARK = "?"
    COLON = ":"
    UNDERSCORE = "_"
    OTHER = "OTHER"


State = int


@dataclass
class NFA:
    """
    NFA over Tok symbols.

    trans: (state, Tok) -> set(next_states)
    eps: state -> set(next_states)
    """
    start: State
    accepts: Set[State]

    trans: Dict[Tuple[State, Tok], Set[State]] = field(default_factory=dict)
    eps: Dict[State, Set[State]] = field(default_factory=dict)

    def add_trans(self, s: State, tok: Tok, t: State) -> None:
        self.trans.setdefault((s, tok), set()).add(t)

    def add_eps(self, s: State, t: State) -> None:
        self.eps.setdefault(s, set()).add(t)


# ------------------------------------------------------------
# Core NFA algorithms
# ------------------------------------------------------------
def eps_closure(nfa: NFA, states: Set[State]) -> Set[State]:
    """Compute ε-closure of a set of NFA states."""
    stack = list(states)
    closure = set(states)
    while stack:
        s = stack.pop()
        for t in nfa.eps.get(s, set()):
            if t not in closure:
                closure.add(t)
                stack.append(t)
    return closure


def move(nfa: NFA, states: Set[State], tok: Tok) -> Set[State]:
    """All states reachable from `states` via one transition on `tok`."""
    out: Set[State] = set()
    for s in states:
        out |= nfa.trans.get((s, tok), set())
    return out


def nfa_accepts_tokens(nfa: NFA, toks: Iterable[Tok]) -> bool:
    """
    Simulate NFA on a token stream.
    Returns True iff the NFA accepts the whole stream.
    """
    current = eps_closure(nfa, {nfa.start})
    for tok in toks:
        nxt = eps_closure(nfa, move(nfa, current, tok))
        if not nxt:
            return False
        current = nxt
    return any(s in nfa.accepts for s in current)


# ------------------------------------------------------------
# Tiny "fragment" builder helpers (hand-built Thompson-style NFAs)
# ------------------------------------------------------------
@dataclass
class Fragment:
    """
    A small NFA fragment with:
    - start state
    - a set of "out" states that should be connected by ε later
    """
    start: State
    outs: Set[State]


class NFABuilder:
    """
    Helper to construct NFAs by allocating new states and wiring transitions.
    This makes it easy to hand-build NFAs for your rules.
    """
    def __init__(self) -> None:
        self._next_state: int = 0
        self._trans: Dict[Tuple[State, Tok], Set[State]] = {}
        self._eps: Dict[State, Set[State]] = {}

    def new_state(self) -> State:
        s = self._next_state
        self._next_state += 1
        return s

    def add_trans(self, s: State, tok: Tok, t: State) -> None:
        self._trans.setdefault((s, tok), set()).add(t)

    def add_eps(self, s: State, t: State) -> None:
        self._eps.setdefault(s, set()).add(t)

    def literal(self, tok: Tok) -> Fragment:
        """
        Fragment for a single token:
           s --tok--> t
        outs={t}
        """
        s = self.new_state()
        t = self.new_state()
        self.add_trans(s, tok, t)
        return Fragment(start=s, outs={t})

    def epsilon(self) -> Fragment:
        """
        Fragment for ε:
           s --ε--> t
        outs={t}
        """
        s = self.new_state()
        t = self.new_state()
        self.add_eps(s, t)
        return Fragment(start=s, outs={t})

    def concat(self, a: Fragment, b: Fragment) -> Fragment:
        """
        Concatenation: connect all outs of a to start of b by ε
        """
        for out in a.outs:
            self.add_eps(out, b.start)
        return Fragment(start=a.start, outs=set(b.outs))

    def union(self, a: Fragment, b: Fragment) -> Fragment:
        """
        Union: new start ε-> a.start and ε-> b.start
               outs = a.outs ∪ b.outs
        """
        s = self.new_state()
        self.add_eps(s, a.start)
        self.add_eps(s, b.start)
        return Fragment(start=s, outs=set(a.outs) | set(b.outs))

    def star(self, a: Fragment) -> Fragment:
        """
        Kleene star:
            new start s is also an out (accept-ready)
            s ε-> a.start
            each out of a ε-> a.start (repeat) and ε-> s (stop)
        """
        s = self.new_state()
        # allow zero repetitions
        outs = {s}
        self.add_eps(s, a.start)
        for out in a.outs:
            self.add_eps(out, a.start)  # repeat
            self.add_eps(out, s)        # stop
        return Fragment(start=s, outs=outs)

    def plus(self, a: Fragment) -> Fragment:
        """
        a+ = a a*
        """
        return self.concat(a, self.star(self._clone_fragment(a)))

    def optional(self, a: Fragment) -> Fragment:
        """
        a? = (a | ε)
        """
        return self.union(a, self.epsilon())

    def _clone_fragment(self, a: Fragment) -> Fragment:
        """
        Shallow clone helper for plus().
        We can't generally clone an arbitrary fragment's graph safely without
        a full AST, so for capstone purposes avoid using plus() unless you build
        the fragment twice manually.

        This method exists to prevent accidental use; it raises by default.
        """
        raise NotImplementedError(
            "NFABuilder.plus() requires rebuilding the fragment explicitly. "
            "Build a second instance of the fragment and then use concat(a, star(b))."
        )

    def finalize(self, frag: Fragment) -> NFA:
        """
        Finalize a fragment into an NFA:
        - create one accept state
        - connect all outs to accept via ε
        """
        accept = self.new_state()
        for out in frag.outs:
            self.add_eps(out, accept)

        # Convert builder internal dicts to NFA
        nfa = NFA(start=frag.start, accepts={accept})
        nfa.trans = self._trans
        nfa.eps = self._eps
        return nfa


# ------------------------------------------------------------
# Example: Hand-built NFA for URL-02 "@ in authority"
# Pattern intent: scheme:// (authority without '/')* then '@'
# Using token classes: LETTER/DIGIT/OTHER etc.
# ------------------------------------------------------------
def build_nfa_url_02_at_in_authority() -> NFA:
    """
    This is an example hand-built NFA using NFABuilder.

    NOTE: Because we're tokenizing into classes, we model:
    - scheme:// as a rough prefix (LETTER/COLON/SLASH) sequence
    - authority loop on any token except SLASH, until AT
    If you prefer exact 'http'/'https' matching, do it as a string-level check
    BEFORE running this NFA (recommended).
    """
    b = NFABuilder()

    # We'll assume scheme already validated externally.
    # Build: (NOT_SLASH)* AT
    # Since Tok doesn't have NOT_SLASH, we approximate by allowing any token except SLASH
    # by building a union of all tokens except SLASH, then star it.

    # Union of allowed tokens in authority (except SLASH)
    allowed = None
    for tok in Tok:
        if tok == Tok.SLASH:
            continue
        frag = b.literal(tok)
        allowed = frag if allowed is None else b.union(allowed, frag)

    assert allowed is not None
    auth_star = b.star(allowed)
    at = b.literal(Tok.AT)
    frag = b.concat(auth_star, at)
    return b.finalize(frag)

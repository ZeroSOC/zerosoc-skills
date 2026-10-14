#!/usr/bin/env python3
"""What carries no information, for the decision scripts of both gates. Standard library only.

Detection & Analysis §2.4: a result that yields no information carries neither side. A lookup that knows
nothing of the indicator, a search that finds no approval and a lookup that was not answered learned
nothing; a check that covered the question and found nothing, such as no child process on a covered host
in the window, learned something and is a real observation, a scoped negative.

A ledger names the first kind under "no_information_refs" and the second under "scoped_negative_refs".
An observation is read without the first kind, on either side: one resting on them alone carries no
weight. A reference cannot be both.

A ledger written before the two lists existed held both kinds under "no_information_refs" and has no
"scoped_negative_refs" key. It is read the same way, which is the safe direction: a scoped negative it
listed there loses its weight, so a Case can be promoted or left undecided on it, never closed on a
lookup that knew nothing. The note says so, and which list the scoped negatives belong in.

triage_decide.py and resolve.py read this module from their own scripts/ directory, where
tools/build_references.py copies it, so the two gates apply one rule.
"""

NOTE = ("the ledger names no scoped_negative_refs: every reference under no_information_refs was read as a"
        " result that carried no information, on both sides (Detection & Analysis §2.4); if it lists a check"
        " that covered the question and found nothing, move that reference to scoped_negative_refs")


def refs(ledger):
    """The references that carried no information, and the note for a ledger that does not list its
    scoped negatives apart. A reference listed as both is an invalid ledger (ValueError)."""
    empty = {str(r) for r in ledger.get("no_information_refs") or [] if r}
    if "scoped_negative_refs" not in ledger:
        return empty, (NOTE if empty else None)
    both = empty & {str(r) for r in ledger.get("scoped_negative_refs") or [] if r}
    if both:
        raise ValueError("a reference is listed both as a scoped negative and as a result that carried no"
                         " information: " + ", ".join(sorted(both)))
    return empty, None


def cited(f):
    """The references an observation rests on, as strings, empty ones left out."""
    return [str(r) for r in (f.get("event_refs") or []) if r]


def informative(f, empty):
    """The references an observation rests on, less those whose result carried no information."""
    return [r for r in cited(f) if r not in empty]


def carries_nothing(f, empty):
    """An observation that cites something, all of it results that carried no information: it is no
    evidence for its side, Malicious or Benign (§2.4)."""
    refs_ = cited(f)
    return bool(refs_) and bool(empty) and all(r in empty for r in refs_)

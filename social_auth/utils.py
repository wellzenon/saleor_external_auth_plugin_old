from typing import Any, Callable, List


def pipe(*list: List[Callable[[Any], Any]]) -> Any:
    first, *rest = list
    for func in rest:
        first = func(first)
    return first

from django import template

register = template.Library()


@register.filter
def num(value):
    if value is None:
        return "–"
    return f"{value:g}" if isinstance(value, float) else value


@register.filter
def label(key):
    return str(key).replace("_", " ")


@register.filter
def grade(rating):
    from core.ratings import grade as to_grade

    return to_grade(rating)


@register.filter
def score_grade(score):
    from core.ratings import score_grade as to_grade

    return to_grade(score) if score is not None else "–"


@register.simple_tag
def rule_for(issue):
    """Catalogue entry for an issue, or None."""
    from core.catalog import lookup

    return lookup(issue.tool, issue.rule)


@register.filter
def get(mapping, key):
    return mapping.get(key) if mapping else None

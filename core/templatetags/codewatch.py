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

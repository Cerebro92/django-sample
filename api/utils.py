from .exceptions import ValidationError


def validate_required_fields(fields):
    errors = {}
    text = 'This field is required.'

    for field, value in fields.items():
        if not value:
            if field in errors:
                errors[field].append(text)
            else:
                errors[field] = [text]

    if errors:
        raise ValidationError(errors=errors)

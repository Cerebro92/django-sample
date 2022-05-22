from rest_framework import serializers


class ChoiceField(serializers.ChoiceField):
    def to_representation(self, value):
        return value if value in ('', None) else self._choices[value]

    def to_internal_value(self, data):
        if data == '' and self.allow_blank:
            return None if self.allow_null else ''

        for key, val in self._choices.items():
            if val == data:
                return key

        self.fail('invalid_choice', input=data)

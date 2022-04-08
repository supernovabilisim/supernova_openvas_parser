import googletrans


class Translator:

    def __init__(self):
        self.translator = googletrans.Translator()

    def translate(self, text_to_translate: str) -> str:

        try:
            translated = self.translator.translate(
                text=text_to_translate,
                src='en', dest='tr'
            )

            return translated.text

        except Exception as e:
            return text_to_translate

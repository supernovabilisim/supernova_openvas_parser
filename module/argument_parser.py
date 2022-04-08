import argparse
import os


def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser()
    directory = os.getcwd()

    parser.add_argument(
        '-rl', '--report-location',
        required=True,
        type=str,
        help=f"Raporun olduğu yer, Örnek kullanım:\
        -rl | --report-location {directory}/report.txt\n"
    )

    parser.add_argument(
        '-dl', '--document-location',
        required=True,
        type=str,
        help=f"Dökümanı kaydedeceğiniz yer, Örnek kullanım:\
        -dl | --document-location {directory}/document.docx\n"
    )

    parser.add_argument(
        '-tl', '--threat-level',
        required=False,
        type=str,
        help="Belli tehdit seviyelerini göstermek için \
        kullanabileceğiniz seçenek ['Düşük', 'Orta', \
        'Yüskek'], istediğniz seviyeleri virgül ile \
        ayırarak yazın. Örnek kullanım:\
        -tl Orta,Yüksek | --threat-level Yüksek"
    )

    parser.add_argument(
        '-d', '--debug',
        action=argparse.BooleanOptionalAction,
        help="Hata ayıklama modunu açma/kapama"
    )

    threat_levels = ['Düşük', 'Orta', 'Yüksek']

    arguments = parser.parse_args()

    if arguments.threat_level is not None:
        arguments.threat_level = arguments.threat_level.split(',')
        for index, argument in enumerate(arguments.threat_level):
            arguments.threat_level[index] = argument.capitalize()
    else:
        arguments.threat_level = threat_levels

    for option in arguments.threat_level:
        if option not in threat_levels:
            print("Bilinmeyen seçenek.")
            exit(1)

    if len(arguments.threat_level) > 3:
        print("Tehdit seviyeleri argümanında üçten fazla seçenek var.")
        exit(1)

    if not os.path.exists(arguments.report_location):
        print(f"Belirttiğiniz yol '{arguments.report_location}' bulunamadı.")
        exit(1)

    return arguments

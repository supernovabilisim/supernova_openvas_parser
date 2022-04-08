from module.file_operations import FileOps
from module.argument_parser import parse_args


def main():

    arguments = parse_args()

    fileops = FileOps(
        report_location=arguments.report_location,
        document_location=arguments.document_location,
        nvt_options=arguments.threat_level,
    )

    file = fileops.read_file()

    found = False

    for index, line in enumerate(file):

        if "Security Issues for Host " in line:
            match = fileops.replace_and_match(
                line=line,
                string_to_replace="Security Issues for Host "
            )

            if match is None:
                continue

            found = True
            fileops.add_to_document(
                first_column='Host',
                second_column=match.group()+"\n"
            )

        if found:
            for name in fileops.ntp_dict:

                if f"{name}:" in line and fileops.ntp_dict[name] == 0:
                    line = line.replace(f'{name}:', '')

                    fileops.add_to_document(
                        first_column=name,
                        second_column=line
                    )

                    fileops.ntp_dict[name] = 1

            for name in fileops.is_dict:

                if f"{name}:" in line and fileops.is_dict[name] == 0:

                    if "References" in line:
                        continue

                    if name in line:
                        fileops.write_multiple_lines(
                            from_line=line,
                            index=index,
                            file=file
                        )
                        fileops.is_dict[name] = 1

                    if "Solution" in line:
                        fileops.find_references(
                            index=index,
                            file=file
                        )
                        fileops.reset_dicts()

            if "Host " in line:
                match = fileops.replace_and_match(
                    line=line,
                    string_to_replace="Host "
                )
                if match is not None:
                    found = False
                    fileops.reset_dicts()

    status = fileops.save_file()

    return status


if __name__ == "__main__":
    main()

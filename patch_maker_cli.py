import os
import sys
import argparse

from patcher import patch_maker


def main():
    parser = argparse.ArgumentParser(
        prog="patch_maker",
        description="Program for creating xdelta patches.",
        epilog=(
            "Example usage:\npatch_maker "
            '--exclude "__Installer/**/*Log.txt" '
            '--optional "__Installer/**" --optional "Support/**" --optional "Core/**" '
            '--always_new "Dead Space.exe" '
            '"Dead Space (2023) v1.1.14.10286" "Dead Space (2023) v1.1.14.12465" '
            '"Dead Space (2023)" 1.1.14.10286 1.1.14.12465'
        ),
    )
    parser.add_argument("old_folder", help="Folder with old version of the game")
    parser.add_argument("new_folder", help="Folder with new version of the game")
    parser.add_argument("game", help="Game name")
    parser.add_argument("old_version", help="Old version of the game")
    parser.add_argument("new_version", help="New version of the game")
    parser.add_argument(
        "--out_folder",
        default=".",
        help="Folder where patch will be created; defaults to working directory",
    )
    parser.add_argument(
        "--test",
        action="append",
        help=(
            'Test patterns; it will test against "old_folder", '
            "other arguments are ignored but must be provided;"
            " can be combined with --include and --exclude;"
            " can be used multiple times"
        ),
    )
    parser.add_argument(
        "--include",
        action="append",
        help=(
            "Files to include; don't use if you want to include all files;"
            " can be used multiple times"
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        help=(
            "Files to exclude; these patterns are applied after the include ones;"
            " can be used multiple times"
        ),
    )
    parser.add_argument(
        "--always_new",
        action="append",
        help=(
            "Files that are always treated as new, even if they don't change;"
            " can be used multiple times"
        ),
    )
    parser.add_argument(
        "--optional",
        action="append",
        help=(
            "Optional files; patcher won't fail if they are missing;"
            " can be used multiple times"
        ),
    )
    parser.add_argument(
        "--language",
        action="append",
        help=(
            "Language files; patcher won't fail if the language you're not using is"
            ' missing; use "<English language name>:<pattern>" format;'
            " can be used multiple times"
        ),
    )
    parser.add_argument(
        "--extension",
        help=(
            "Extension of xdelta files stored in patch archive; defaults to "
            '"patch-<old_version>-<new_version>", with dots replaced with underscores'
        ),
    )
    parser.add_argument(
        "--old_hashes",
        help=(
            "Path to .md5 file with old hashes; must use forward slashes, must be "
            'in "<md5 hash> *<relative path>" format'
        ),
    )
    parser.add_argument(
        "--new_hashes",
        help=(
            "Path to .md5 file with old hashes; must use forward slashes, must be "
            'in "<md5 hash> *<relative path>" format'
        ),
    )
    parser.add_argument("--crack_path")
    parser.add_argument("--crack_password")

    args = parser.parse_args()

    if args.test is not None:
        files_set = patch_maker.get_files_set(args.old_folder)
        if args.include is not None:
            files_set = patch_maker.filter_files(files_set, args.include)
        files_set -= patch_maker.filter_files(files_set, args.exclude)
        print(patch_maker.test_patterns(files_set, args.test))
        return

    language_files = None
    if args.language is not None:
        language_files = {}
        for x in args.language:
            lang, pattern = x.split(":", 1)
            try:
                language_files[lang].append(pattern)
            except KeyError:
                language_files[lang] = [pattern]

    extension = args.extension
    if extension is None:
        extension = f"patch-{args.old_version}-{args.new_version}".replace(".", "_")

    old_hashes = {}
    new_hashes = {}
    for hash_dict, file_path in (
        (old_hashes, args.old_hashes),
        (new_hashes, args.new_hashes),
    ):
        if file_path is not None:
            with open(file_path, encoding="utf-8") as f:
                for line in f.read().split("\n"):
                    try:
                        md5, path = line.split(" *", 1)
                    except ValueError:
                        continue
                    hash_dict[path] = md5

    filename = f"{args.game} Patch {args.new_version} from {args.old_version}.patch"
    output_file = os.path.join(args.out_folder, filename)
    if os.path.isfile(output_file) and os.path.getsize(output_file) != 0:
        print(f'Patch file ("{output_file}") already exists.')
    with open(output_file, "wb"):
        pass

    p = patch_maker.PatchMaker(args.game)
    p.make_patch(
        output_file,
        args.old_version,
        args.new_version,
        args.old_folder,
        args.new_folder,
        extension,
        crack_path=args.crack_path,
        crack_password=args.crack_password,
        hashes_from=old_hashes,
        hashes_to=new_hashes,
        include_files=args.include,
        exclude_files=args.exclude,
        always_new=args.always_new,
        language_files=language_files,
        optional_files=args.optional,
    )

if __name__ == "__main__":
    main()

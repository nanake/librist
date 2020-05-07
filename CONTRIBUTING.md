# librist contribution guide

## CoC
The [VideoLAN Code of Conduct](https://wiki.videolan.org/CoC) applies fully to this project.

## ToDo

The todo list can be found [on the wiki](https://code.videolan.org/rist/librist/wikis/to-do).

## Codebase language

The codebase is developed with the following assumptions:

For the library:
- C language with C99 version, without the VLA or the Complex (*\_\_STDC_NO_COMPLEX__*) features, and without compiler extension,
- arm/arm64 in .S files, using the GAS syntax limited to subset llvm 5.0's internal assembler supports,

For the tools and utils:
- C *(see above for restrictions)*

If you want to use *Threads* or *Atomic* features, please conform to the **C11**/**POSIX** semantic and use a wrapper for older compilers/platforms *(like done in VLC)*.

Please use modern standard POSIX functions *(strscpy, asprintf, tdestroy)*, and provide a compatibility fallback *(like done in VLC)*.

We will make reasonable efforts for compilers that are a bit older, but we won't support gcc 3 or MSVC 2012.

## Authorship

Please provide a correct authorship for your commit logs, with a name and a valid email.

We will reject anonymous contributions for now. As an exception, known pseudonyms from the multimedia community are accepted.

## Commit logs

Please read [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/).

## Submit requests (WIP)

- Code,
- [Compile](https://xkcd.com/303/),
- Check your [code style](https://code.videolan.org/rist/librist/wikis/Coding-style),
- Test,
- Try,
- Submit patches through merge requests,
- Check that this passes the CI.

## Patent license

This code was written to comply with the Video Services Forum (VSF) Technical Recommendations TR-06-1 and TR-06-2 and as such is free of any patent royalty payments

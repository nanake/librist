#stub file
librist_git_dir = join_paths(librist_src_root, '.git')
rev_target = vcs_tag(command: [
        'git', '--git-dir', librist_git_dir,
        'describe', '--tags', '--long',
        '--match', '?.*.*', '--always'
    ],
    input: 'vcs_version.h.in',
    output: 'vcs_version.h'
)
subdir('librist')
# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# SPDX-License-Identifier: BSD-2-Clause

#stub file
librist_git_dir = join_paths(librist_src_root, '.git')
rev_target = vcs_tag(command: [
        'git', '--git-dir', librist_git_dir,
		'--work-tree', meson.source_root(),
        'describe', '--tags', '--dirty',
        '--match', 'v?.*', '--always'
    ],
    input: 'vcs_version.h.in',
    output: 'vcs_version.h'
)
subdir('librist')

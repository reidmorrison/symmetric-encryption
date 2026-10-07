---
paths:
  - "docs/**"
---

# Documentation site

**The look and feel is not in this repo.** `docs/_config.yml` sets
`remote_theme: reidmorrison/rm-docs-theme@v1`, and the layout, stylesheet,
sidebar and syntax highlighting all come from there. This repo holds only its
own content: the markdown pages and `docs/images`.

- **Do not add a `docs/_layouts` or `docs/stylesheets` directory.** They were
  deleted deliberately. Six gem repos each carried a near-identical copy of the
  same theme, and the copies had drifted: the mobile header fix that lives in
  this repo's history never reached the other five. A styling change belongs in
  `rm-docs-theme`, where it reaches every doc site at once.
- **`v1` is a moving major tag.** Fixes to the theme arrive on this site's next
  build without a change here. Breaking changes go to `v2` and are opted into
  by editing the pin above.
- **A page's title lives in its front matter**, not in a `## Heading` at the top
  of the markdown. The theme renders it as the page's `h1`. `index.md` sets
  `heading` rather than `title`, so the home page keeps the tuned SEO `<title>`
  in `_config.yml` while displaying a different headline.
- **Adding or renaming a page** means editing the `nav` block in
  `docs/_config.yml`, the `pages` list in the `llms_full` rake task, and
  `docs/llms.txt`.
- **`jekyll-remote-theme` must stay in `plugins`.** GitHub Pages enables it on
  its own, but a local build does not, and without it every page silently
  renders with no layout.

To preview the site against a local checkout of the theme:

```bash
~/src/rm-docs-theme/bin/preview ~/src/symmetric-encryption/docs
```

Plain `bundle exec jekyll serve` also works, but it fetches the published `v1`
tag rather than any local theme changes.

# Documentation website

The site is intentionally buildless: plain HTML, CSS, and JavaScript are published directly through GitHub Pages.

Preview locally from the repository root:

```bash
python3 -m http.server 4173 --directory website
```

Then open `http://localhost:4173`.

After the branch is merged, open **Settings → Pages** and select **GitHub Actions** as the publishing source. The Pages workflow deploys `website/` after every push to `main`.

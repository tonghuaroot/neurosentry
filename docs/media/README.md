# Product media

Screenshots and a guided-tour recording of the NeuroSentry console, captured
automatically from the live app. **Do not hand-edit these files** — regenerate:

```bash
# Screenshots + tour video (Playwright drives the live console)
NS_BASE=http://<host>:8080 node scripts/capture-media.mjs
# Convert the recording to GIF + MP4 (ffmpeg)
./scripts/media-to-gif.sh
```

## Guided tour

![Guided tour](guided-tour.gif)

Also available as [guided-tour.mp4](guided-tour.mp4) (smaller, higher quality).

## Views

| | |
|---|---|
| ![Overview](screenshots/overview.png) **Overview** — triage queue + KPIs | ![Attack chain](screenshots/attack-chain.png) **Attack chain** — cross-layer finding |
| ![Knowledge Base](screenshots/kb.png) **Knowledge Base** — rules library | ![KB article](screenshots/kb-article.png) **KB article** — rule explained |
| ![AI Gateway](screenshots/gateway.png) **AI Gateway** — tool-call allow/block | ![Threat Correlation](screenshots/threats.png) **Threat Correlation** |
| ![Cases](screenshots/cases.png) **Cases** — SOC workbench | ![Detections](screenshots/detections.png) **Detections** — rule library |
| ![Fleet](screenshots/fleet.png) **Fleet** — control plane | ![Audit Trail](screenshots/audit.png) **Audit Trail** — hash-chained log |

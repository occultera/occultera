# Name and logo

**English** · [Türkçe](Name-and-Logo-TR)

<p align="center"><img src="images/occultera-mark.svg" alt="Occultera logo" width="220"></p>

**Occultera** was called **wazuh-daily-triage** until release 0.11.1. The code, the configuration and the data
are the same; only the name, the logo and the addresses changed (see [Upgrade](Upgrade#0120)).

## Where the name comes from

Astronomers who want to see something faint next to something very bright put a disk in front of the bright
source. The disk is called an **occulter**. With the glare blocked, what was hidden next to it becomes visible:
the Sun's corona, or a dim planet beside its star. Coronagraphs on the ground and in space work this way.

A SIEM has the same problem. Thousands of alerts a day are bright and mostly expected; the one that matters is
faint and sits right next to them. Occultera blocks the known noise — baselines, accepted findings, rules you
already understood — so that what is left is worth a human look.

## What the logo shows

| Part | Meaning |
|---|---|
| Dark disk | the occulter: the known noise, blocked on purpose |
| Corona, gold and blue | everything that is still there, seen in context |
| One bright flash at the rim | the signal that gets through |
| Blue brackets around the flash | the watch has locked on to it |
| Radar arc with ticks | it is tracked until a human decides |

**Slogan:** *Find the signal in the dark.*

## Files

The source files are in [`docs/assets`](https://github.com/occultera/occultera/tree/main/docs/assets):
`occultera-mark.svg` (logo), `occultera-lockup.svg` (logo with name and slogan), `occultera-square.svg`
and `occultera-social-1280x640.png`. Colours: background `#0A0F1A`, disk `#05080F`, gold `#FFD27A`,
blue `#7FD3FF`, text `#F2EFE6`. Font: Space Grotesk (SIL Open Font License).

## What did not change

Environment variables (`WDT_*`), index names (`daily-triage-*`), metric names (`wdt_*`) and the Kustomize
resource names stay as they were, so existing installations upgrade in place without moving data. The Helm chart
and the backup archives carry the new name (see [Upgrade](Upgrade#0120)).

---

*Applies to 0.12.0 · reviewed 2026-11-16*

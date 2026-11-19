# Diagram Studio symbol palette (`color` and `iso3d` libraries)

Source of truth: `../palette.py` (both generators import it). Values are
`#RRGGBB`; the generators never emit `currentColor` or gradients, so the
element colour in the editor and the exporters never repaints these icons.

## Families

Colour follows the **function** of the object (a firewall is red although its
category is `network.firewall`; a user is amber although its category is
`security.user`).

| Family | tint | light | base | dark | ink | ink : light | ink : tint | ink : white |
|---|---|---|---|---|---|---|---|---|
| network (blues) | `#DCEBFF` | `#8DB8FA` | `#3B7DED` | `#1F56C7` | `#173A80` | 5.3 | 8.9 | 10.8 |
| security (reds / oranges) | `#FFE5E0` | `#F9A894` | `#E8513A` | `#B5301F` | `#7A1D12` | 5.5 | 8.7 | 10.4 |
| infra (slate) | `#E3E9F0` | `#9EAEC2` | `#62748C` | `#3B4A5E` | `#1F2937` | 6.5 | 12.0 | 14.7 |
| devices (teal) | `#D5F5EF` | `#6FD6C6` | `#18A391` | `#0E7365` | `#0B4A42` | 5.8 | 8.8 | 10.1 |
| data (violets) | `#EEE8FF` | `#BFADF8` | `#8A63E8` | `#6236C4` | `#40207F` | 6.1 | 10.2 | 12.1 |
| software (greens) | `#DDF6E4` | `#83DCA0` | `#2EAD5B` | `#1C7E40` | `#134F29` | 5.8 | 8.4 | 9.6 |
| people (ambers) | `#FFF1D0` | `#F8CD6A` | `#E79B12` | `#AD6608` | `#6E3F07` | 5.9 | 7.9 | 8.8 |
| generic (neutral) | `#E9EDF3` | `#B4BFCD` | `#7D8BA0` | `#4B596D` | `#253041` | 7.1 | 11.3 | 13.3 |

Contrast columns are WCAG ratios of the glyph colour (ink) against each body
fill. Rule: **glyph vs body >= 3:1**; every family clears it with margin
(lowest 5.3:1). `tests/test_diagram_symbols_variants.py` recomputes them.

## Roles in the flat colour icons (`color/`)

| Role | Paint | Used for |
|---|---|---|
| outline / glyph lines | ink | every stroke |
| body | light | the largest closed shape of the icon |
| panel | `#FFFFFF` | closed shapes inside the body (screens, bays, cards) |
| tint | tint | other closed shapes and dashed zones |
| accent | base | small closed marks (LED, badge, star) |
| dots | ink | small solid marks |

## Shading of the 3D icons (`iso3d/`)

One 2:1 isometric projection; each solid uses three shades of its colour:
top = colour mixed 30 % toward white, left face = colour, right face = colour
mixed 24 % toward black. Shared accents: status LED `#22C55E`, warning
`#F59E0B`, alert `#EF4444`, info `#38BDF8`, screen glass `#1E293B`, port
`#0F172A`, ground shadow `#0F172A` at 13 % opacity.

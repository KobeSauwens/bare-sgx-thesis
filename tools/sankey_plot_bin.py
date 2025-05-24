import json
import plotly.graph_objects as go

# Load your JSON
with open("output.json") as f:
    data = json.load(f)

# Build label list
labels = []
label_map = {}
sources = []
targets = []
values = []

def get_label_index(label):
    if label not in label_map:
        label_map[label] = len(labels)
        labels.append(label)
    return label_map[label]

# First category: is_hacl → function name
for entry in data:
    group = "HACL*" if entry["is_hacl"] else "Other"
    func = entry["name"]
    size = entry["size_bytes"]

    src = get_label_index(group)
    tgt = get_label_index(func)

    sources.append(src)
    targets.append(tgt)
    values.append(size)

# Create Sankey diagram
fig = go.Figure(go.Sankey(
    node=dict(
        pad=15,
        thickness=20,
        line=dict(color="black", width=0.5),
        label=labels,
    ),
    link=dict(
        source=sources,
        target=targets,
        value=values,
    )
))

fig.update_layout(title_text="Function Size Flow: HACL* vs Other", font_size=12)
fig.show()


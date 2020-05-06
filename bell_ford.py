"""
Bellman Ford routing algorithm to help with RIP protocol assignment
inspiration from https://iopscience.iop.org/article/10.1088/1742-6596/1007/1/012009/pdf
"""

INFINITY = float("inf") #positive infinity

def bellman_ford(verts, edges, current):
    dist = []
    prev = []

    for index, this in enumerate(verts):
        if current == this:
            dist[index] = 0
        else:
            dist[index] = INFINITY
            prev[index] = None

    for i in range(1, len(verts) - 1):
        for edge in edges:
            u, v, w = edge
            if (dist[u] + w) < dist[v]:
                dist[v] = dist[u] + w
                prev[v] = u

    for edge in edges:
        u, v, w = edge
        if (dist[u] + w) < dist[v]:
            return ValueError("negative weight cycle: broken")

    return dist, prev

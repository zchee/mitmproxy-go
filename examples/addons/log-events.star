"""Write messages at the four levels used by the upstream example."""

def on_load(loader):
    ctx.log.info("This is some informative text.")
    ctx.log.warn("This is a warning.")
    ctx.log.error("This is an error.")
    ctx.log.alert("This is an alert. It has the same urgency as info, but will also pop up in the status bar.")

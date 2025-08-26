const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");
tm.readTodo().then((data) => {
  const available = data.tasks.filter(
    (t) => t.status === "pending" && !t.assigned_agent && !t.claimed_by,
  );
  console.log("Available unclaimed tasks:");
  available.forEach((t) => {
    console.log(
      `- ${t.id}: ${t.title} [${t.category}/${t.priority}] deps: ${t.dependencies ? t.dependencies.length : 0}`,
    );
  });

  console.log("\nIn progress tasks:");
  const inProgress = data.tasks.filter((t) => t.status === "in_progress");
  inProgress.forEach((t) => {
    console.log(
      `- ${t.id}: ${t.title} [${t.category}] assigned: ${t.assigned_agent || t.claimed_by || "none"}`,
    );
  });
});

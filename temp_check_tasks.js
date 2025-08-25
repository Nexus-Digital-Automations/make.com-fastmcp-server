const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");

tm.readTodo()
  .then((data) => {
    console.log("All tasks:");
    data.tasks.forEach((t) => {
      console.log(
        `- ${t.id}: ${t.title} | Status: ${t.status} | Assigned: ${t.assigned_agent || t.claimed_by || "none"} | Category: ${t.category}`,
      );
    });

    const available = data.tasks.filter(
      (t) => t.status === "pending" && !t.assigned_agent && !t.claimed_by,
    );
    console.log("\nAvailable unclaimed tasks:");
    if (available.length === 0) {
      console.log("No available tasks found");
    } else {
      available.forEach((t) => {
        console.log(`- ${t.id}: ${t.title} (${t.category}, ${t.priority})`);
      });
    }
  })
  .catch((error) => {
    console.error("Error:", error.message);
  });

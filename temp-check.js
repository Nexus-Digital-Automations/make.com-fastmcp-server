const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");
tm.readTodo().then((data) => {
  const available = data.tasks.filter(
    (t) => t.status === "pending" && !t.assigned_agent && !t.claimed_by,
  );
  console.log("Available unclaimed tasks:", available.length);
  if (available.length > 0) {
    available.forEach((t) =>
      console.log("- " + t.id + ": " + t.title + " (" + t.category + ")"),
    );
  } else {
    console.log("✅ All tasks completed - no available work");
  }
});

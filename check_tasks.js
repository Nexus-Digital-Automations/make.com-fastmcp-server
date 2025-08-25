const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");
tm.readTodo().then((data) => {
  const available = data.tasks.filter(
    (t) =>
      t.status === "pending" &&
      t.assigned_agent == null &&
      t.claimed_by == null,
  );
  console.log(
    "Available tasks:",
    available.map((t) => ({ id: t.id, title: t.title, category: t.category })),
  );
});

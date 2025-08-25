const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");
tm.readTodo().then(data => {
  const available = data.tasks.filter(t => t.status === "pending" && !t.assigned_agent && !t.claimed_by);
  console.log("Available tasks:");
  available.forEach(t => console.log(`- ${t.id}: ${t.title} (${t.category}, ${t.priority})`));
});

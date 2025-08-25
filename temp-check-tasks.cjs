const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");

async function checkAvailableTasks() {
  const tm = new TaskManager("./TODO.json");
  const data = await tm.readTodo();
  
  const available = data.tasks.filter(t => 
    t.status === "pending" && 
    !t.assigned_agent && 
    !t.claimed_by
  );
  
  console.log("Available tasks:");
  available.forEach(t => {
    console.log(`- ${t.id}: ${t.title} (${t.category}, ${t.priority})`);
  });
  
  return available;
}

checkAvailableTasks().catch(console.error);
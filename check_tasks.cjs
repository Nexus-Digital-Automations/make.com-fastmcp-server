const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.readTodo().then(data => {
  console.log('All tasks:');
  data.tasks.forEach(t => console.log('- ' + t.id + ': ' + t.title + ' (status: ' + t.status + ')'));
  const pending = data.tasks.filter(t => t.status === 'pending');
  console.log('
Pending tasks:', pending.length);
});

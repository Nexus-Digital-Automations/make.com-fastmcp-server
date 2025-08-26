const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");

tm.claimTask("task_1756166559507_19enblxud", "development_session_1756166376482_1_general_97143e97", "normal").then(result => {
    console.log("✅ Task claimed successfully:");
    console.log(JSON.stringify(result, null, 2));
}).catch(err => console.error("Error:", err));
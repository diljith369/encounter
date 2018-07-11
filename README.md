## Encounter 
### A framework for threat hunting. Works on client/Server architecture. Agent can be created separately using its own GUI provided. Agent should run as Administrator[root] . Once the agent is up and running server gets notification from the agent and user can start threat hunting on agent running machine. All hunts result will be available as HTML reports along with necessary extra web links.

### Getting Started
##### git clone https://github.com/diljithishere/encounter.git

### Additional modules to install 
#### go get github.com/fatih/color
#### go get github.com/gorilla/mux
#### go get github.com/PuerkitoBio/goquery

#### Build Encounter server 
##### move to sourcecode folder
##### go build encounter.go  (default listening port is 7777)

#### Build Encounter agent 
##### move to sourcecode/encagent folder
##### set GOARCH=386
##### go build createagent.go 
##### run the createagent.exe (default listening port is 7778) , user can access the app using ip and port through browser, supply your IP address and port number of encounter server and click on Generate button. User can download the agent.exe to the target machine by clicking the download button. Run agent.exe as administrator, your server will greet with hunting options.

#### Prerequisites
##### git & Go 

#### Built with 
##### Go 

### Note 
#### It is a prototype and development in progress.

### Author
#### * **Diljith S** - *Initial work* - (https://github.com/diljithishere)







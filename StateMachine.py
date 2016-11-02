class StateMachine():
    def __init__(self):
       self.states = []
       self.num_states = 0

    def pushState(self, state):
        self.states.append(state)
        self.num_states += 1
        state.onEnter()

    def popState(self):
        if self.num_states > 0:
            self.states.pop().onExit()
            self.num_states -= 1

    def changeState(self, state):
        if self.num_states > 0:
            self.states.pop().onExit()
            self.num_states -= 1
        self.states.append(state)
        self.num_states += 1
        state.onEnter()


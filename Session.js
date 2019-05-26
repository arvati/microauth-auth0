const crypto = require('crypto');

class Session {
    constructor({noState = false, PKCE = false}){
        this.code_verifier = PKCE;
        this._states = [];
        this._prompt = true;
        this.noState = noState;
    }
    set code_verifier(PKCE){
        this._code_verifier = !PKCE ? null : crypto.randomBytes(32)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }
    get code_verifier(){
      return this._code_verifier
    }
    set prompt(value){
      this._prompt = value
    }
    get prompt(){
      return this._prompt
    }
    set noState(value){
      this._noState = value
    }
    get noState(){
      return this._noState
    }
    addState(state){
      if (!this._noState) this._states.push(state);
    }
    delState(state){
      if (!this._noState) this._states.splice(this._states.indexOf(state), 1);
    }
    verifyState(state){
      return (!this._noState && !this._states.includes(state)) ? false : true
    }
  }
module.exports = Session;
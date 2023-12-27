const HistroyReducer=(state = {data:null},action)=>{
    switch(action.type){
        case 'POST_HISTROY':
            return {...state, data: action?.data};
        case 'FETCH_ALL_HISTROY_VIDEOS':
            return {...state,data:action.payload};
            
        default:
            return state;
    }
}

export default HistroyReducer;
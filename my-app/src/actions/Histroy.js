import * as api from '../api';

export const addToHistroy = (HistroyData) => async (dispatch) => {
  try {
    const { data } = await api.addToHistroy(HistroyData);
    console.log(HistroyData);
    dispatch({ type: "POST_HISTROY", data });
    dispatch(getAllHistroy());
  } catch (error) {
    console.log(error);
  }
};

export const getAllHistroy = () => async (dispatch) => {
  try {
    const { data } = await api.getAllHistroy();
    console.log(data);
    dispatch({ type: 'FETCH_ALL_HISTROY_VIDEOS', payload: data });
  } catch (error) {
    console.log(error);
  }
};

export const clearHistroy =(HistroyData)=>async(dispatch)=>{
  try{
    const {userId}=HistroyData;
    await api.deleteHistroy(userId);
    dispatch(getAllHistroy());
  } catch(error){
    console.log(error)
  }
}



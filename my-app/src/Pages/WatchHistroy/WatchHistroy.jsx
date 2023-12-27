import React from 'react';
import vid from '../../Components/Video/vid.mp4'
import WHL from '../../Components/WHL/WHL';
import { useSelector } from 'react-redux';

function WatchHistroy() {
  const histroyList = useSelector(state => state.HistroyReducer);
  return (
    <WHL page={"Histroy"} videoList={histroyList}/>
  )
}  
export default WatchHistroy
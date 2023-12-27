import React from 'react';
import vid from '../../Components/Video/vid.mp4'
import WHL from '../../Components/WHL/WHL';
import { useSelector } from 'react-redux';
function WatchLater() {


  const WatchLaterList = useSelector(state => state.WatchLaterReducer);
  console.log(WatchLaterList)

  return (
    <WHL page={"Watch Later"} videoList={WatchLaterList}/>
  )
}  

export default WatchLater
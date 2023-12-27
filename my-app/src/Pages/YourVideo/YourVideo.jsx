import React from 'react';
import vid from '../../Components/Video/vid.mp4'
import LeftSideBar from '../../Components/LeftSideBar/LeftSideBar'
import ShowVideoGrid from '../../Components/ShowVideoGrid/ShowVideoGrid';
import './YourVideo.css'
import { useSelector } from 'react-redux';

function YourVideo() {
  const CurrentUser = useSelector((state) => state?.currentUserReducer);
  const vids = useSelector(state => state.videoReducer)?.data?.filter(q => q?.videoChanel === CurrentUser?.result?._id).reverse();

  return (
    <div className='Container_pages_App'>
        <LeftSideBar/>
        <div className='Container2_pages_App'>
          <div className='container_YourVideo'>
          <h1>Your Video</h1>
          {
            CurrentUser ? (
              <>
                <ShowVideoGrid vids={vids}/>
              </>
            ) : (
              <>
                <h3>Please Login to see uploaded video</h3>
              </>
            )
          }
          
          </div>
        </div>
    </div>
  )
}

export default YourVideo;

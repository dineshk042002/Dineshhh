import React from 'react';
import LeftSideBar from '../../Components/LeftSideBar/LeftSideBar';
import './Library.css';
import { FaHistory } from 'react-icons/fa';

import vid from '../../Components/Video/vid.mp4';
import WHLVideoList from '../../Components/WHL/WHLVideoList';
import { MdOutlineWatchLater } from 'react-icons/md';
import { AiOutlineLike } from 'react-icons/ai';
import { useSelector } from 'react-redux';

function Library() {
  const vids = [
    {
      _id: 1,
      video_src: vid,
      chanel: 'cdd',
      title: 'Video1',
      Uploader: 'abc',
      description: 'description of the video',
    },
    {
      _id: 2,
      video_src: vid,
      chanel: 'cdd',
      title: 'Video2',
      Uploader: 'abc',
      description: 'description of the video',
    },
    {
      _id: 3,
      video_src: vid,
      chanel: 'add',
      title: 'Video3',
      Uploader: 'abc',
      description: 'description of the video',
    },
    {
      _id: 4,
      video_src: vid,
      chanel: 'add',
      title: 'Video3',
      Uploader: 'abc',
      description: 'description of the video',
    },
  ];

  const CurrentUser = useSelector(state => state?.currentUserReducer);
  const histroyList = useSelector(state=>state.HistroyReducer)
  const WatchLaterList = useSelector(state=>state.watchLaterReducer)
  const likedVideoList = useSelector(state=>state.likedVideoReducer)
  return (
    <div className='container_Pages_App'>
      <LeftSideBar />
      <div className='container2_Pages_App'>
        <div className='container_libraryPage'>
            <h1 className='title_container_libraypage'>
              <b>
                <FaHistory />
              </b>
              <b>History</b>
            </h1>
            <div className='container_videoList_libraryPage'>
               <WHLVideoList page={"Histroy"} 
               CurrentUser={CurrentUser?.result._id}
               videoList={histroyList} />
            </div>
          </div>
          <div className='container_libraryPage'>
            <h1 className='title_container_libraypage'>
              <b>
                <MdOutlineWatchLater/>
              </b>
              <b>WatchLater</b>
            </h1>
            <div className='container_videoList_libraryPage'>
               <WHLVideoList page={"Watch Later"}
               CurrentUser={CurrentUser?.result._id}
               videoList={WatchLaterList} />
            </div>
          </div>
          <div className='container_libraryPage'>
            <h1 className='title_container_libraypage'>
              <b>
                <AiOutlineLike/>
              </b>
              <b>Like videos</b>
            </h1>
            <div className='container_videoList_libraryPage'>
               <WHLVideoList page={"LikedVideos"} 
               CurrentUser={CurrentUser?.result._id}
               videoList={likedVideoList} />
            </div>
          </div>
        </div>
      </div>
    
  );
}

export default Library;

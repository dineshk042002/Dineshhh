import React from 'react';
import LeftSideBar from '../../Components/LeftSideBar/LeftSideBar';
import './Library.css';
import { FaHistory } from 'react-icons/fa';

import vid from '../../Components/Video/vid.mp4';

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

  return (
    <div className='container_Pages_App'>
      <LeftSideBar />
      <div className='container2_Pages_App'>
        <div className='container_libraryPage'>
          <div className='container2_librarypage'>
            <h1 className='title_container_libraypage'>
              <b>
                <FaHistory />
              </b>
              <b>History</b>
            </h1>
            <div className='container_videoList_libraryPage'>
              {vids.map((video) => (
                <div key={video._id} className='video_item'>
                  <video src={video.video_src} controls />
                  <h2>{video.title}</h2>
                  <p>{video.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Library;

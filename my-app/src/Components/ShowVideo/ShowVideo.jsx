import React from 'react';
import {Link} from 'react-router-dom'
import moment from 'moment'
import './ShowVideo.css';

function ShowVideo({ vid }) {
  console.log(vid)
  return (
    <>
      <Link to={`/VideoPage/${vid?._id}`}>
        
          <video
        
          src={`http://localhost:5500/${vid.filePath}`}
          //src={`https://dineshkk.onrender.com/${vid.filePath}`}
            className='video_ShowVideo'
          />
      </Link>
      <div className='video_description'>
        <div className='Chanel_logo_App'>
          <div className='fstChar_logo_App'>
            <p>{vid?.Uploader?.charAt(0).toUpperCase()}</p>
          </div>
        </div>
        <div className='video_details'>
          <p className='title_vid_ShowVideo'>{vid?.videoTitle}</p>
          <pre className='vid_view_UploadTime'>{vid?.Uploader}</pre>
          <pre className='vid_view_UploadTime'>
            {vid?.Views} views <div className='dot'></div> {moment(vid?.createdAt).fromNow()}
          </pre>
        </div>
      </div>
    </>
  );
}

export default ShowVideo;

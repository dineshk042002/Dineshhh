// Import necessary dependencies
import React, { useEffect } from 'react';
import './VideoPage.css';
import LikeWatchLaterSaveBtns from './LikeWatchLaterSaveBtns';
import Comments from '../../Components/Comments/Comments';
import { Link, useParams } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import moment from 'moment';
import { addToHistroy } from '../../actions/Histroy';
import { viewVideo } from '../../actions/video';

function VideoPage() {
  // Get video ID from the URL params
  const { vid } = useParams();

  // Redux state for video and current user
  const vids = useSelector((state) => state.videoReducer);
  const vv = vids?.data.filter((q) => q._id === vid)[0];
  const dispatch = useDispatch();
  const currentUser = useSelector((state) => state?.currentUserReducer);

  // Function to handle adding to history
  const handleHistroy = () => {
    dispatch(
      addToHistroy({
        videoId: vid,
        Viewer: currentUser?.result._id,
      })
    );
  };

  // Function to handle increasing views
  const handleViews = () => {
    dispatch(viewVideo({ id: vid }));
  };

  // useEffect to run actions on component mount
  useEffect(() => {
    if (currentUser) {
      handleHistroy();
    }
    handleViews();
  }, [currentUser, vid]); // Include currentUser and vid in the dependency array

  return (
    <>
      <div className='container_videoPage'>
        <div className='container2_videoPage'>
          <div className='video_display_screen_videoPage'>
            {/* Use a source tag for better compatibility */}
            <video
              controls
              autoPlay
              className='video_ShowVideo_videoPage'
            >
              <source
              //src={`http://localhost:5500//${vv?.filePath}`}
              src={`https://dineshkk.onrender.com/${vv?.filePath}`}
                type='video/mp4' // Adjust the type based on your video format
              />
              Your browser does not support the video tag.
            </video>
            <div className='video_details_videoPage'>
              <div className='video_btns_title_VideoPage'>
                <p className='video_title_VideoPage'>{vv?.videoTitle}</p>
                <div className='views_date_btns_VideoPage'>
                  <div className='views_videoPage'>
                    {vv?.Views} views <div className='dot'></div>{' '}
                    {moment(vv?.createdAt).fromNow()}
                  </div>
                </div>
                <LikeWatchLaterSaveBtns vv={vv} vid={vid} />
              </div>
              <Link to={`/chanel/${vv?.videoChanel}`} className='Chanel_details_videoPage'>
                <b className='chanel_logo_videoPage'>
                  <p>{vv?.Uploader.charAt(0).toUpperCase()}</p>
                </b>
                <p className='chanel_name_videoPage'>{vv?.Uploader}</p>
              </Link>
              <div className='comments_videoPage'>
                <h2>
                  <u>comments</u>
                </h2>
                <Comments videoId={vv._id} />
              </div>
            </div>
          </div>
          <div className='moreVideoBar'>More video</div>
        </div>
      </div>
    </>
  );
}

export default VideoPage;

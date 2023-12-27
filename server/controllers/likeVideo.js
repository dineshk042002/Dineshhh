import likedVideo from '../models/likedVideo.js';
import mongoose from 'mongoose';

export const likeVideoController = async (req, res) => {
  try {
    const likedVideoData = req.body;

    const addToLikedVideo = new likedVideo(likedVideoData);

    await addToLikedVideo.save();
    res.status(200).json('Added to likedVideo');
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
};

export const getAlllikeVideoController = async (req, res) => {
  try {
    const files = await likedVideo.find();
    res.status(200).json(files);
  } catch (error) {
    res.status(404).json({ error: error.message });
  }
};
export const deleteLikeVideoController=async(req, res)=>{
  const { videoId:videoId, Viewer:Viewer}=req.params;
  console.log(videoId,Viewer)
  try{
    await likedVideo.findOneAndDelete({
      videoId: videoId, Viewer:Viewer
    })
    res.status(200).json({message: "Removed from your watch Laters"})
  }catch(error){
    res.status(404).json({message: error.message})
  }
}
import comment from '../models/comments.js'
import mongoose from 'mongoose'


export const postComment = async (req, res) => {
  
    const commentData = req.body;

    const postComment = new comment(commentData);
  try {
    await postComment.save();
    res.status(200).json('posted the comment');
    //console.log("DONE")
  } catch (error) {
    console.error('Error:', error);
    
  }
};

export const getComment = async (req, res) => {
    try {
      const commentList = await comment.find();
      res.status(200).json(commentList);
    } catch (error) {
      res.status(404).json(error.message);
    }
  };
  
  export const deleteComment=async(req, res)=>{
    const { id:_id}=req.params;
    if (!mongoose.Types.ObjectId.isValid(_id)) {
      return res.status(404).send("Comment Unavailable...");
    }
    try{
      await comment.findByIdAndRemove(_id)
      res.status(200).json({message: "Delete the comment"})
    }catch(error){
      res.status(404).json({message: error.message})
    }
  }
  export const editComment=async(req, res)=>{
    const {id:_id}=req.params;
    const {commentBody}=req.body;
    if (!mongoose.Types.ObjectId.isValid(_id)) {
      return res.status(404).send("comment Unavailable...");
    }
    try{
        const updateComment = await comment.findByIdUpdate(
            _id,
            {
                $set:{"commentBody" : commentBody}
            }
            )
            res.status(200).json(updateComment)
    }catch(error){
        res.status(404).json(error)
    }
  }
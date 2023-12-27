import Histroy from '../models/Histroy.js';
import mongoose from 'mongoose';

export const HistroyController = async (req, res) => {
  
    const HistroyData = req.body;

    //console.log(HistroyData)
    const addToHistroy = new Histroy(HistroyData);
  try {
    await addToHistroy.save();
    res.status(200).json('Added to watch Later Video');
    //console.log("DONE")
  } catch (error) {
    console.error('Error:', error);
    
  }
};

export const getAllHistroyController = async (req, res) => {
  try {
    const files = await Histroy.find();
    res.status(200).json(files);
  } catch (error) {
    res.status(404).json(error.message);
  }
};

export const deleteHistroyController=async(req, res)=>{
  const { userId:userId}=req.params;
  //console.log(userId)
  try{
    await Histroy.deleteMany({
      Viewer:userId
    })
    res.status(200).json({message: "Removed from your watch Laters"})
  }catch(error){
    res.status(404).json({message: error.message})
  }
}
import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { XCircle } from 'lucide-react';
import { 
  PaintBrushIcon, 
  DocumentTextIcon,
  Square2StackIcon,
  TrashIcon,
  ArrowUturnDownIcon,
  SwatchIcon
} from '@heroicons/react/24/outline';
import { ChessGame, WordPuzzle, MemoryGame, SudokuGame } from './Rooms/GameRoom.jsx';
import { MusicRoom } from './Rooms/MusicRoom.jsx';
import ArtRoom from './Rooms/ArtRoom.jsx';

// Color Picker Component
const ColorPicker = ({ selectedColor, onColorChange }) => {
  const colors = [
    // Primary Colors
    '#FF0000', '#0000FF', '#FFFF00',
    // Secondary Colors
    '#00FF00', '#FF00FF', '#00FFFF',
    // Earth Tones
    '#8B4513', '#A0522D', '#6B4423',
    // Grayscale
    '#000000', '#808080', '#FFFFFF',
    // Additional Colors
    '#FFA500', '#800080', '#008000',
    '#FF69B4', '#4B0082', '#FFD700'
  ];

  return (
    <div className="flex flex-wrap justify-center gap-2 w-full max-w-md mx-auto">
      {colors.map(color => (
        <button
          key={color}
          className={`w-8 h-8 sm:w-10 sm:h-10 rounded-full border-2 ${
            selectedColor === color ? 'border-[#508D4E]' : 'border-gray-300'
          } hover:scale-110 transition-transform shadow-sm`}
          style={{ backgroundColor: color }}
          onClick={() => onColorChange(color)}
        />
      ))}
    </div>
  );
};

// Canvas Component
const Canvas = ({ selectedTool, onSave }) => {
  const canvasRef = useRef(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const [context, setContext] = useState(null);
  const [color, setColor] = useState('#000000');
  const [brushSize, setBrushSize] = useState(5);
  const [history, setHistory] = useState([]);
  const [currentStep, setCurrentStep] = useState(-1);
  const [lastX, setLastX] = useState(0);
  const [lastY, setLastY] = useState(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = color;
    ctx.lineWidth = brushSize;
    setContext(ctx);
    
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    saveState();
  }, []);

  useEffect(() => {
    if (context) {
      context.strokeStyle = color;
      context.lineWidth = brushSize;
    }
  }, [color, brushSize]);

  const saveState = () => {
    const canvas = canvasRef.current;
    const newHistory = history.slice(0, currentStep + 1);
    newHistory.push(canvas.toDataURL());
    setHistory(newHistory);
    setCurrentStep(newHistory.length - 1);
  };

  const undo = () => {
    if (currentStep > 0) {
      const img = new Image();
      img.src = history[currentStep - 1];
      img.onload = () => {
        context.clearRect(0, 0, canvasRef.current.width, canvasRef.current.height);
        context.drawImage(img, 0, 0);
        setCurrentStep(currentStep - 1);
      };
    }
  };

  const clearCanvas = () => {
    context.fillStyle = '#FFFFFF';
    context.fillRect(0, 0, canvasRef.current.width, canvasRef.current.height);
    saveState();
  };

  const getMousePos = (e) => {
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    
    return {
      x: (e.clientX - rect.left) * scaleX,
      y: (e.clientY - rect.top) * scaleY
    };
  };

  const startDrawing = (e) => {
    const pos = getMousePos(e);
    setIsDrawing(true);
    setLastX(pos.x);
    setLastY(pos.y);
    context.beginPath();
    context.moveTo(pos.x, pos.y);
  };

  const draw = (e) => {
    if (!isDrawing) return;
    
    const pos = getMousePos(e);
    
    if (selectedTool === 'eraser') {
      context.strokeStyle = '#FFFFFF';
    } else {
      context.strokeStyle = color;
    }
    
    context.beginPath();
    context.moveTo(lastX, lastY);
    context.lineTo(pos.x, pos.y);
    context.stroke();
    
    setLastX(pos.x);
    setLastY(pos.y);
  };

  const stopDrawing = () => {
    if (isDrawing) {
      context.closePath();
      setIsDrawing(false);
      saveState();
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto">
      <div className="bg-white rounded-xl shadow-xl p-4 sm:p-6 space-y-6">
        {/* Tools Section */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          {/* Left Side - Tools */}
          <div className="flex flex-wrap justify-center gap-3 w-full sm:w-auto">
            {/* Brush and Eraser Tools */}
            <button
              onClick={() => setSelectedTool('brush')}
              className={`px-4 py-2 rounded-lg flex items-center space-x-2 ${
                selectedTool === 'brush'
                  ? 'bg-[#508D4E] text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              <PaintBrushIcon className="w-5 h-5" />
              <span>Brush</span>
            </button>
            <button
              onClick={() => setSelectedTool('eraser')}
              className={`px-4 py-2 rounded-lg flex items-center space-x-2 ${
                selectedTool === 'eraser'
                  ? 'bg-[#508D4E] text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              <SwatchIcon className="w-5 h-5" />
              <span>Eraser</span>
            </button>

            {/* Action Icons */}
            <div className="flex space-x-2">
              <button
                onClick={undo}
                className="p-2 rounded-lg hover:bg-gray-100 disabled:opacity-50"
                disabled={currentStep <= 0}
                title="Undo"
              >
                <ArrowUturnDownIcon className="w-5 h-5 text-gray-600" />
              </button>
              <button
                onClick={clearCanvas}
                className="p-2 rounded-lg hover:bg-gray-100"
                title="Clear Canvas"
              >
                <TrashIcon className="w-5 h-5 text-gray-600" />
              </button>
              <button
                onClick={handleSave}
                className="p-2 rounded-lg hover:bg-gray-100"
                title="Save Artwork"
              >
                <Square2StackIcon className="w-5 h-5 text-gray-600" />
              </button>
            </div>
          </div>

          {/* Right Side - Brush Size */}
          <div className="flex items-center space-x-2 w-full sm:w-auto">
            <label className="text-sm text-gray-600 whitespace-nowrap">Brush Size:</label>
            <input
              type="range"
              min="1"
              max="50"
              value={brushSize}
              onChange={(e) => setBrushSize(e.target.value)}
              className="w-32 sm:w-40"
            />
          </div>
        </div>

        {/* Color Picker */}
        <div className="py-2">
          <ColorPicker selectedColor={color} onColorChange={setColor} />
        </div>
        
        {/* Canvas Container */}
        <div className="relative w-full" style={{ paddingBottom: '90%' }}>
          <canvas
            ref={canvasRef}
            width={1200}
            height={1000}
            className="absolute top-0 left-0 w-full h-full border border-gray-300 rounded-lg cursor-crosshair touch-none"
            onMouseDown={startDrawing}
            onMouseMove={draw}
            onMouseUp={stopDrawing}
            onMouseOut={stopDrawing}
            onTouchStart={startDrawing}
            onTouchMove={draw}
            onTouchEnd={stopDrawing}
          />
        </div>
      </div>
    </div>
  );
};

// Artwork Card Component
const ArtworkCard = ({ artwork, onDelete }) => {
  return (
    <div className="relative bg-white rounded-xl shadow-lg p-4">
      <img
        src={artwork.imageUrl}
        alt={artwork.title}
        className="w-full aspect-square object-cover rounded-lg"
      />
      <div className="mt-2">
        <h3 className="font-semibold text-gray-800">{artwork.title}</h3>
        <p className="text-sm text-gray-600">By {artwork.artist}</p>
      </div>
      {onDelete && (
        <button
          onClick={() => onDelete(artwork.id)}
          className="absolute top-2 right-2 p-1 rounded-full bg-white/90 hover:bg-red-100 transition-colors"
        >
          <TrashIcon className="w-5 h-5 text-red-600" />
        </button>
      )}
    </div>
  );
};

// Game Room Component
export const GameRoom = () => {
  const [selectedGame, setSelectedGame] = useState(null);
  const [players, setPlayers] = useState([]);

  const games = [
    { id: 'chess', name: 'Chess', minPlayers: 2, maxPlayers: 2, component: ChessGame },
    { id: 'wordscape', name: 'Word Puzzle', minPlayers: 1, maxPlayers: 1, component: WordPuzzle },
    { id: 'memory', name: 'Memory Cards', minPlayers: 1, maxPlayers: 4, component: MemoryGame },
    { id: 'sudoku', name: 'Sudoku', minPlayers: 1, maxPlayers: 1, component: SudokuGame }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-100 to-blue-50 p-4 sm:p-6 md:p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl sm:text-4xl font-bold text-blue-900 mb-6 sm:mb-8">Game Room</h1>
        
        {!selectedGame ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
            {games.map((game) => (
              <div 
                key={game.id}
                className="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-2xl transition-all duration-300 transform hover:-translate-y-1 cursor-pointer border border-blue-100"
                onClick={() => setSelectedGame(game)}
              >
                <h3 className="text-xl sm:text-2xl font-semibold mb-2 sm:mb-3 text-blue-800">{game.name}</h3>
                <p className="text-blue-600 text-sm sm:text-base">
                  {game.minPlayers === game.maxPlayers 
                    ? `${game.minPlayers} player${game.minPlayers > 1 ? 's' : ''}`
                    : `${game.minPlayers}-${game.maxPlayers} players`}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <div className="relative">
            <button
              onClick={() => setSelectedGame(null)}
              className="absolute right-2 sm:right-4 top-2 sm:top-4 z-10 p-2 rounded-full bg-white/90 hover:bg-white transition-colors shadow-md"
            >
              <XCircle className="w-5 h-5 sm:w-6 sm:h-6 text-blue-600 hover:text-blue-800" />
            </button>
            
            <div className="bg-white rounded-xl shadow-xl p-4 sm:p-8 border border-blue-100">
              <h2 className="text-2xl sm:text-3xl font-bold text-blue-800 mb-4 sm:mb-6">{selectedGame.name}</h2>
              
              <div className="w-full flex justify-center">
                {selectedGame.component && <selectedGame.component />}
              </div>
              
              <div className="mt-4 sm:mt-6 text-xs sm:text-sm text-blue-600 text-center font-medium">
                {selectedGame.minPlayers === selectedGame.maxPlayers 
                  ? `${selectedGame.minPlayers} player${selectedGame.minPlayers > 1 ? 's' : ''} required`
                  : `${selectedGame.minPlayers}-${selectedGame.maxPlayers} players allowed`}
              </div>
            </div>
          </div>
        )}
        
        <div className="mt-8 sm:mt-12 bg-white rounded-xl shadow-xl p-4 sm:p-8 border border-blue-100">
          <h3 className="text-xl sm:text-2xl font-semibold mb-4 sm:mb-6 text-blue-800">Gaming Tips</h3>
          <div className="grid sm:grid-cols-2 gap-6 sm:gap-8">
            <div>
              <h4 className="text-lg sm:text-xl font-medium text-blue-700 mb-3 sm:mb-4">For the Best Experience</h4>
              <ul className="space-y-2 sm:space-y-3 text-blue-600 text-sm sm:text-base">
                <li className="flex items-center">
                  <span className="mr-2 sm:mr-3 text-blue-400">•</span>
                  Take regular breaks between games
                </li>
                <li className="flex items-center">
                  <span className="mr-2 sm:mr-3 text-blue-400">•</span>
                  Try different games to exercise various skills
                </li>
              </ul>
            </div>
            <div>
              <h4 className="text-lg sm:text-xl font-medium text-blue-700 mb-3 sm:mb-4">Game Benefits</h4>
              <ul className="space-y-2 sm:space-y-3 text-blue-600 text-sm sm:text-base">
                <li className="flex items-center">
                  <span className="mr-2 sm:mr-3 text-blue-400">•</span>
                  Enhances cognitive function
                </li>
                <li className="flex items-center">
                  <span className="mr-2 sm:mr-3 text-blue-400">•</span>
                  Provides stress relief through engaging activities
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Export the imported ArtRoom
export { ArtRoom };

// Export MusicRoom
export { MusicRoom };
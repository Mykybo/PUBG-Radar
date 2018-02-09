package pubg.radar

import pubg.radar.sniffer.Sniffer
import pubg.radar.ui.GLMap

const val gridWidth = 813000f
const val mapWidth = 819200f
const val mapWidthCropped = 8192

var gameStarted = false
var isErangel = true

interface GameListener {
  fun onGameStart() {}
  fun onGameOver()
}

private val gameListeners = ArrayList<GameListener>()

fun register(gameListener: GameListener) {
  gameListeners.add(gameListener)
}

fun deregister(gameListener: GameListener) {
  gameListeners.remove(gameListener)
}

fun gameStart() {
  gameStarted = true
  gameListeners.forEach { it.onGameStart() }
}

fun gameOver() {
  gameStarted = false
  gameListeners.forEach { it.onGameOver() }
}

lateinit var Args:Array<String>
fun main(args: Array<String>) {
  Args=args
  if(args.size<2){
    println("usage: <ip> <sniff option>")
    System.exit(-1)
  }
  Sniffer.sniffLocationOnline()
  val ui = GLMap()
  ui.show()
}
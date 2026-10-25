package com.demo

import java.util.Random

class Shuffler {
    private val tileRandom = Random()

    fun pickTile(tiles: List<String>): String {
        val random = Random()
        val index = random.nextInt(tiles.size)
        return tiles[index]
    }

    fun nextColor(): Int = tileRandom.nextInt(0xFFFFFF)
}

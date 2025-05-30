import { DateTime } from 'luxon'
import hash from '@adonisjs/core/services/hash'
import { BaseModel, column, beforeSave } from '@adonisjs/lucid/orm'
import { DbAccessTokensProvider } from '@adonisjs/auth/access_tokens'

export default class User extends BaseModel {
  @column({ isPrimary: true })
  declare id: number

  @column()
  declare username: string | null

  @column()
  declare email: string

  @column({ serializeAs: null })
  declare passwordHash: string

  @column()
  declare role: 'Spectator' | 'User' | 'Editor' | 'Admin'

  @column.dateTime({ autoCreate: true })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  declare updatedAt: DateTime | null

  // Hook para hashear la contraseña antes de guardar el usuario
  @beforeSave()
  public static async hashPassword(user: User) {
    // Verifica si el passwordHash ha cambiado
    if (user.$dirty.passwordHash) {
      user.passwordHash = await hash.make(user.passwordHash)
    }
  }

  static accessTokens = DbAccessTokensProvider.forModel(User)
}
